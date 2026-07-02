import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from analyzer import analyze, parse_line  # noqa: E402


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
    # 6 failures but spread 30s apart -> never 5 within a 60s window.
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
