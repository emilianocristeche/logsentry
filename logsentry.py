#!/usr/bin/env python3
"""LogSentry CLI — scan an sshd auth log for security events.

Usage:
  python logsentry.py sample_auth.log
  python logsentry.py /var/log/auth.log --threshold 8 --window 120
  python logsentry.py sample_auth.log --json
"""

from __future__ import annotations

import argparse
import json
import sys

from analyzer import analyze


def _fmt_ts(dt) -> str:
    return dt.strftime("%b %d %H:%M:%S") if dt else "?"


def _print_report(r: dict) -> None:
    print("\nLogSentry report")
    print("=" * 48)
    print(f"lines parsed:        {r['lines_parsed']}")
    print(f"failed logins:       {r['total_failed']}")
    print(f"successful logins:   {r['total_accepted']}")
    print(f"unique source IPs:   {r['unique_attacker_ips']}")

    if r["compromised"]:
        print("\n[!!] LIKELY COMPROMISE - brute force followed by a successful login:")
        for c in r["compromised"]:
            print(f"     {c['ip']}  ({c['total_failures']} failed, then logged in)")

    if r["brute_force"]:
        print("\n[!] Brute-force sources:")
        for b in r["brute_force"]:
            flag = "  <-- got in!" if b["successful_login"] else ""
            print(f"     {b['ip']:<16} {b['failures_in_window']} fails in window "
                  f"({_fmt_ts(b['window_start'])} to {_fmt_ts(b['window_end'])}){flag}")
    else:
        print("\nNo brute-force activity above threshold.")

    if r["top_offenders"]:
        print("\nTop offender IPs (by failed logins):")
        for ip, n in r["top_offenders"]:
            print(f"     {ip:<16} {n}")

    if r["invalid_users"]:
        print("\nProbed non-existent usernames (recon):")
        for user, n in r["invalid_users"]:
            print(f"     {user:<16} {n}")
    print()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Scan an sshd auth log for security events.")
    p.add_argument("logfile", help="path to an auth log (e.g. /var/log/auth.log)")
    p.add_argument("--threshold", type=int, default=5,
                   help="failed logins from one IP within the window to flag as brute force (default 5)")
    p.add_argument("--window", type=int, default=60,
                   help="time window in seconds for the threshold (default 60)")
    p.add_argument("--year", type=int, default=2024,
                   help="year to assume for syslog timestamps (default 2024)")
    p.add_argument("--json", action="store_true", help="emit findings as JSON")
    args = p.parse_args(argv)

    try:
        with open(args.logfile, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        print(f"error: cannot read {args.logfile}: {e}", file=sys.stderr)
        return 2

    r = analyze(lines, threshold=args.threshold, window_seconds=args.window, year=args.year)

    if args.json:
        # datetimes -> ISO strings for a clean JSON payload.
        def _enc(o):
            if hasattr(o, "isoformat"):
                return o.isoformat()
            raise TypeError
        print(json.dumps(r, default=_enc, indent=2))
    else:
        _print_report(r)

    # Exit non-zero if anything alarming was found — handy for cron / CI alerts.
    return 1 if r["brute_force"] else 0


if __name__ == "__main__":
    sys.exit(main())
