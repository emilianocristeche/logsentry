import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from analyzer import analyze, parse_line, parse_timestamp  # noqa: E402


def test_parse_failed_invalid_user():
    e = parse_line(
        "Jun 10 13:55:31 web01 sshd[3300]: Failed password for invalid user admin "
        "from 203.0.113.5 port 40001 ssh2"
    )
    assert e["event"] == "failed"
    assert e["user"] == "admin"
    assert e["ip"] == "203.0.113.5"
    assert e["invalid"] is True
    assert e["ts"] is not None


def test_parse_accepted():
    e = parse_line(
        "Jun 10 08:12:03 web01 sshd[2011]: Accepted password for emiliano "
        "from 198.51.100.2 port 51022 ssh2"
    )
    assert e["event"] == "accepted"
    assert e["user"] == "emiliano"
    assert e["invalid"] is False


def test_parse_irrelevant_line_returns_none():
    assert parse_line("Jun 10 08:00:00 web01 systemd[1]: Started Daily apt timer.") is None


def _bruteforce_log(ip, n, start_sec=0):
    return [
        f"Jun 10 13:55:{start_sec + i:02d} web01 sshd[1]: "
        f"Failed password for root from {ip} port {40000 + i} ssh2"
        for i in range(n)
    ]


def test_brute_force_detected_above_threshold():
    r = analyze(_bruteforce_log("203.0.113.5", 6), threshold=5, window_seconds=60)
    assert len(r["brute_force"]) == 1
    assert r["brute_force"][0]["ip"] == "203.0.113.5"
    assert r["brute_force"][0]["failures_in_window"] == 6


def test_below_threshold_not_flagged():
    r = analyze(_bruteforce_log("203.0.113.5", 3), threshold=5, window_seconds=60)
    assert r["brute_force"] == []


def test_slow_attack_outside_window_not_flagged():
    # 6 failures spread 60s apart (one per minute) -> never 5 within a 60s window.
    lines = [
        f"Jun 10 13:{55 + i}:00 web01 sshd[1]: Failed password for root "
        f"from 203.0.113.5 port {40000 + i} ssh2"
        for i in range(6)
    ]
    r = analyze(lines, threshold=5, window_seconds=60)
    assert r["brute_force"] == []


def test_compromise_flagged_when_success_follows_bruteforce():
    lines = _bruteforce_log("203.0.113.5", 5) + [
        "Jun 10 13:55:52 web01 sshd[1]: Accepted password for root "
        "from 203.0.113.5 port 40099 ssh2"
    ]
    r = analyze(lines, threshold=5, window_seconds=60)
    assert len(r["compromised"]) == 1
    assert r["compromised"][0]["ip"] == "203.0.113.5"


def test_end_to_end_on_sample_file():
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_auth.log")
    with open(path, encoding="utf-8") as f:
        r = analyze(f.readlines(), threshold=5, window_seconds=60)
    ips = {b["ip"] for b in r["brute_force"]}
    assert "203.0.113.5" in ips and "192.0.2.77" in ips
    assert {c["ip"] for c in r["compromised"]} == {"203.0.113.5"}


def test_success_before_burst_is_not_compromise():
    # Same IP logged in hours *before* attacking: no evidence the attack worked.
    lines = [
        "Jun 10 09:00:00 web01 sshd[1]: Accepted password for root "
        "from 203.0.113.5 port 40099 ssh2"
    ] + _bruteforce_log("203.0.113.5", 5)
    r = analyze(lines, threshold=5, window_seconds=60)
    assert len(r["brute_force"]) == 1
    assert r["brute_force"][0]["successful_login"] is False
    assert r["compromised"] == []


def test_parse_accepted_publickey():
    e = parse_line(
        "Jun 10 08:45:17 web01 sshd[2044]: Accepted publickey for deploy "
        "from 198.51.100.9 port 51110 ssh2: ED25519 SHA256:abc"
    )
    assert e["event"] == "accepted"
    assert e["method"] == "publickey"
    assert e["user"] == "deploy"


def test_parse_ipv6_source_is_normalized():
    e = parse_line(
        "Jun 10 13:55:31 web01 sshd[1]: Failed password for root "
        "from 2001:db8:0:0::5 port 40001 ssh2"
    )
    assert e["ip"] == "2001:db8::5"


def test_ipv6_brute_force_and_compromise():
    lines = [
        f"Jun 10 13:55:{i:02d} web01 sshd[1]: Failed password for root "
        f"from 2001:db8::5 port {40000 + i} ssh2"
        for i in range(5)
    ] + ["Jun 10 13:56:00 web01 sshd[1]: Accepted password for root from 2001:db8::5 port 1 ssh2"]
    r = analyze(lines, threshold=5, window_seconds=60)
    assert [c["ip"] for c in r["compromised"]] == ["2001:db8::5"]


def test_parse_iso8601_timestamp_with_offset():
    e = parse_line(
        "2025-06-10T13:55:31.123456-03:00 web01 sshd[1]: Failed password for root "
        "from 203.0.113.5 port 40001 ssh2"
    )
    # Converted to UTC.
    assert e["ts"] == datetime(2025, 6, 10, 16, 55, 31, 123456)


def test_iso8601_brute_force():
    lines = [
        f"2025-06-10T13:55:{i:02d}Z web01 sshd[1]: Failed password for root "
        f"from 203.0.113.5 port {40000 + i} ssh2"
        for i in range(6)
    ]
    r = analyze(lines, threshold=5, window_seconds=60)
    assert r["brute_force"][0]["failures_in_window"] == 6


def test_feb_29_infers_most_recent_leap_year():
    now = datetime(2026, 10, 15)
    ts = parse_timestamp("Feb 29 10:00:00 web01 sshd[1]: x", now=now)
    assert ts == datetime(2024, 2, 29, 10, 0, 0)


def test_feb_29_with_explicit_non_leap_year_is_unparseable():
    assert parse_timestamp("Feb 29 10:00:00 web01 sshd[1]: x", year=2025) is None


def test_december_lines_read_in_january_belong_to_last_year():
    now = datetime(2026, 1, 2)
    assert parse_timestamp("Dec 31 23:59:59 web01 sshd[1]: x", now=now).year == 2025
    assert parse_timestamp("Jan 01 00:00:01 web01 sshd[1]: x", now=now).year == 2026


def test_analyze_consumes_a_one_shot_iterator():
    # Streaming: analyze() must work on a generator (single pass, no len()).
    r = analyze((ln for ln in _bruteforce_log("203.0.113.5", 6)), threshold=5)
    assert r["brute_force"][0]["failures_in_window"] == 6
