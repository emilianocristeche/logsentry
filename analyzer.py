"""LogSentry — parse Linux sshd auth logs and flag security events.

Pure functions, Python standard library only. No web framework, no database —
this is a CLI / systems tool on purpose, to sit alongside a web-app project and
show a different skill set (log parsing, detection logic, the command line).

Detections:
  - brute force: >= threshold failed logins from one IP within a time window
  - likely compromise: a successful login from a brute-forcing IP that happens
    at or after the start of its burst
  - recon: attempts against invalid (non-existent) usernames
  - top offender IPs by failed-login count

Input is consumed as a stream (any iterable of lines, e.g. an open file), so
large logs are never loaded into memory whole. Only per-IP timestamps are kept.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

# Timestamp prefixes. Classic syslog ("Jun 10 13:55:31") carries no year;
# RFC 3339 / ISO-8601 (rsyslog high-precision, journalctl -o short-iso) does.
_SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b")
_ISO_TS = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s"
)
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# sshd messages. The auth method is captured so any of password, publickey,
# keyboard-interactive/pam, etc. is recognized. The source address is taken as
# a token (IPv4 or IPv6) and normalized afterwards.
_FAILED = re.compile(r"Failed (\S+) for (invalid user )?(\S+) from (\S+)")
_ACCEPTED = re.compile(r"Accepted (\S+) for (\S+) from (\S+)")
_INVALID = re.compile(r"Invalid user (\S*) from (\S+)")

# How far back to look when inferring a syslog year. 8 years always contains
# a leap year, so a Feb 29 entry resolves to the most recent one.
_YEAR_LOOKBACK = 8


def _norm_ip(token: str) -> str:
    """Canonical form for IPs (so 2001:db8:0::1 == 2001:db8::1); other tokens as-is."""
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return token


def _infer_year(month: int, day: int, h: int, m: int, s: int, now: datetime) -> datetime | None:
    """Most recent past occurrence of this month/day/time relative to `now`.

    Handles a Dec->Jan rollover (December lines read in January belong to last
    year) and Feb 29 (resolves to the latest leap year) without a fixed year.
    One day of slack absorbs clock/timezone skew between log host and reader.
    """
    for y in range(now.year, now.year - _YEAR_LOOKBACK, -1):
        try:
            dt = datetime(y, month, day, h, m, s)
        except ValueError:      # e.g. Feb 29 in a non-leap year
            continue
        if dt <= now + timedelta(days=1):
            return dt
    return None


def parse_timestamp(line: str, year: int | None = None,
                    now: datetime | None = None) -> datetime | None:
    """Timestamp of a log line as a naive datetime, or None if unparseable.

    ISO-8601 timestamps with an offset are converted to UTC. Syslog timestamps
    are local wall-clock time; their year is `year` if given, else inferred.
    """
    m = _ISO_TS.match(line)
    if m:
        try:
            dt = datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
        except ValueError:
            return None
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt

    m = _SYSLOG_TS.match(line)
    if not m or m.group(1) not in _MONTHS:
        return None
    month = _MONTHS[m.group(1)]
    day, h, mi, s = (int(g) for g in m.groups()[1:])
    if year is not None:
        try:
            return datetime(year, month, day, h, mi, s)
        except ValueError:      # explicit year that has no such date
            return None
    return _infer_year(month, day, h, mi, s, now or datetime.now())


def parse_line(line: str, year: int | None = None,
               now: datetime | None = None) -> dict | None:
    """Parse one log line into {ts, event, method, user, ip, invalid} or None.

    event is one of: 'failed', 'accepted'. 'Invalid user' lines also count as a
    failed attempt and set invalid=True.
    """
    m = _FAILED.search(line)
    if m:
        event = {"event": "failed", "method": m.group(1), "user": m.group(3),
                 "ip": _norm_ip(m.group(4)), "invalid": m.group(2) is not None}
    elif (m := _ACCEPTED.search(line)):
        event = {"event": "accepted", "method": m.group(1), "user": m.group(2),
                 "ip": _norm_ip(m.group(3)), "invalid": False}
    elif (m := _INVALID.search(line)):
        event = {"event": "failed", "method": None, "user": m.group(1),
                 "ip": _norm_ip(m.group(2)), "invalid": True}
    else:
        return None
    event["ts"] = parse_timestamp(line, year, now)
    return event


def _max_in_window(times: list[datetime], window_seconds: int) -> tuple[int, datetime, datetime]:
    """Max number of events falling within any window_seconds span.

    Returns (count, window_start, window_end). Two-pointer sweep over sorted times.
    """
    times = sorted(t for t in times if t is not None)
    if not times:
        return 0, None, None
    best = 1
    best_lo = best_hi = times[0]
    lo = 0
    for hi in range(len(times)):
        while (times[hi] - times[lo]).total_seconds() > window_seconds:
            lo += 1
        span = hi - lo + 1
        if span > best:
            best, best_lo, best_hi = span, times[lo], times[hi]
    return best, best_lo, best_hi


def analyze(lines, threshold: int = 5, window_seconds: int = 60,
            year: int | None = None, now: datetime | None = None) -> dict:
    """Analyze an iterable of log lines in a single pass.

    Returns a findings dict (JSON-serializable except datetimes). `now` is the
    reference point for syslog year inference; it defaults to the current time.
    """
    now = now or datetime.now()

    lines_parsed = total_failed = total_accepted = 0
    fails_by_ip = defaultdict(list)     # ip -> [timestamps]
    accepts_by_ip = defaultdict(list)   # ip -> [timestamps]
    invalid_users = Counter()

    for line in lines:
        e = parse_line(line, year, now)
        if e is None:
            continue
        lines_parsed += 1
        if e["event"] == "failed":
            total_failed += 1
            fails_by_ip[e["ip"]].append(e["ts"])
            if e["invalid"]:
                invalid_users[e["user"]] += 1
        else:
            total_accepted += 1
            accepts_by_ip[e["ip"]].append(e["ts"])

    fail_count = Counter({ip: len(ts) for ip, ts in fails_by_ip.items()})

    brute_force = []
    for ip, times in fails_by_ip.items():
        count, start, end = _max_in_window(times, window_seconds)
        if count >= threshold:
            # Only a success at/after the burst began is evidence the attack
            # worked; a login hours earlier from the same IP is not.
            later = sorted(t for t in accepts_by_ip.get(ip, []) if t is not None and t >= start)
            brute_force.append({
                "ip": ip,
                "failures_in_window": count,
                "total_failures": fail_count[ip],
                "window_start": start,
                "window_end": end,
                "successful_login": bool(later),
                "first_success_after_burst": later[0] if later else None,
            })
    brute_force.sort(key=lambda b: b["failures_in_window"], reverse=True)

    compromised = [b for b in brute_force if b["successful_login"]]

    return {
        "lines_parsed": lines_parsed,
        "total_failed": total_failed,
        "total_accepted": total_accepted,
        "unique_attacker_ips": len(fails_by_ip),
        "brute_force": brute_force,
        "compromised": compromised,
        "top_offenders": fail_count.most_common(5),
        "invalid_users": invalid_users.most_common(5),
    }


def _selfcheck() -> None:
    log = [
        "Jun 10 13:55:36 srv sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 4022 ssh2",
        "Jun 10 13:55:38 srv sshd[1]: Failed password for root from 203.0.113.5 port 4023 ssh2",
        "Jun 10 13:55:40 srv sshd[1]: Failed password for root from 203.0.113.5 port 4024 ssh2",
        "Jun 10 13:55:42 srv sshd[1]: Failed password for root from 203.0.113.5 port 4025 ssh2",
        "Jun 10 13:55:44 srv sshd[1]: Failed password for root from 203.0.113.5 port 4026 ssh2",
        "Jun 10 13:55:50 srv sshd[1]: Accepted password for root from 203.0.113.5 port 4027 ssh2",
        "Jun 10 13:56:00 srv sshd[1]: Accepted password for emiliano from 198.51.100.2 port 5001 ssh2",
    ]
    r = analyze(iter(log), threshold=5, window_seconds=60)
    assert r["total_failed"] == 5, r["total_failed"]
    assert r["total_accepted"] == 2
    assert len(r["brute_force"]) == 1
    assert r["brute_force"][0]["ip"] == "203.0.113.5"
    assert r["brute_force"][0]["failures_in_window"] == 5
    # The attacker IP logged in successfully after the burst -> compromise.
    assert len(r["compromised"]) == 1
    assert r["compromised"][0]["ip"] == "203.0.113.5"
    assert dict(r["invalid_users"]).get("admin") == 1
    # A quiet legit IP must not be flagged.
    assert all(b["ip"] != "198.51.100.2" for b in r["brute_force"])
    # A success that happened *before* the burst is not a compromise.
    r = analyze([log[5].replace("13:55:50", "09:00:00")] + log[:5])
    assert r["compromised"] == [], r["compromised"]
    print("analyzer self-check OK")


if __name__ == "__main__":
    _selfcheck()
