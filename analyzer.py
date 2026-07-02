"""LogSentry — parse Linux sshd auth logs and flag security events.

Pure functions, Python standard library only. No web framework, no database —
this is a CLI / systems tool on purpose, to sit alongside a web-app project and
show a different skill set (log parsing, detection logic, the command line).

Detections:
  - brute force: >= threshold failed logins from one IP within a time window
  - likely compromise: a successful login from an IP that was brute-forcing
  - recon: attempts against invalid (non-existent) usernames
  - top offender IPs by failed-login count
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime

# sshd log line shapes (syslog prefix + message).
_TS = re.compile(r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)")
_FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
_ACCEPTED = re.compile(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)")
_INVALID = re.compile(r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)")

# syslog timestamps carry no year. Assume one; a Dec->Jan rollover in a single
# file would skew windows, which we accept for a log-triage tool.
# ponytail: fixed default year; pass year= if you analyze a specific period.
_DEFAULT_YEAR = 2024


def parse_line(line: str, year: int = _DEFAULT_YEAR) -> dict | None:
    """Parse one log line into {ts, event, user, ip} or None if irrelevant.

    event is one of: 'failed', 'accepted'. 'Invalid user' lines also count as a
    failed attempt and set invalid=True.
    """
    ts_match = _TS.search(line)
    ts = None
    if ts_match:
        raw = re.sub(r"\s+", " ", ts_match.group(1)).strip()
        try:
            ts = datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")
        except ValueError:
            ts = None

    invalid = "invalid user" in line.lower()

    m = _FAILED.search(line)
    if m:
        return {"ts": ts, "event": "failed", "user": m.group(1), "ip": m.group(2),
                "invalid": invalid}
    m = _ACCEPTED.search(line)
    if m:
        return {"ts": ts, "event": "accepted", "user": m.group(1), "ip": m.group(2),
                "invalid": False}
    m = _INVALID.search(line)
    if m:
        return {"ts": ts, "event": "failed", "user": m.group(1), "ip": m.group(2),
                "invalid": True}
    return None


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
            year: int = _DEFAULT_YEAR) -> dict:
    """Analyze log lines. Returns a findings dict (JSON-serializable except datetimes)."""
    events = [e for e in (parse_line(ln, year) for ln in lines) if e]

    failed = [e for e in events if e["event"] == "failed"]
    accepted = [e for e in events if e["event"] == "accepted"]

    fails_by_ip = defaultdict(list)   # ip -> [timestamps]
    fail_count = Counter()
    for e in failed:
        fails_by_ip[e["ip"]].append(e["ts"])
        fail_count[e["ip"]] += 1

    accepted_ips = {e["ip"] for e in accepted}

    brute_force = []
    for ip, times in fails_by_ip.items():
        count, start, end = _max_in_window(times, window_seconds)
        if count >= threshold:
            brute_force.append({
                "ip": ip,
                "failures_in_window": count,
                "total_failures": fail_count[ip],
                "window_start": start,
                "window_end": end,
                # A success from an IP that was hammering us is the loud signal.
                "successful_login": ip in accepted_ips,
            })
    brute_force.sort(key=lambda b: b["failures_in_window"], reverse=True)

    compromised = [b for b in brute_force if b["successful_login"]]
    invalid_users = Counter(e["user"] for e in failed if e["invalid"])

    return {
        "lines_parsed": len(events),
        "total_failed": len(failed),
        "total_accepted": len(accepted),
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
    r = analyze(log, threshold=5, window_seconds=60)
    assert r["total_failed"] == 5, r["total_failed"]
    assert r["total_accepted"] == 2
    assert len(r["brute_force"]) == 1
    assert r["brute_force"][0]["ip"] == "203.0.113.5"
    assert r["brute_force"][0]["failures_in_window"] == 5
    # The attacker IP later logged in successfully -> compromise.
    assert len(r["compromised"]) == 1
    assert r["compromised"][0]["ip"] == "203.0.113.5"
    assert dict(r["invalid_users"]).get("admin") == 1
    # A quiet legit IP must not be flagged.
    assert all(b["ip"] != "198.51.100.2" for b in r["brute_force"])
    print("analyzer self-check OK")


if __name__ == "__main__":
    _selfcheck()
