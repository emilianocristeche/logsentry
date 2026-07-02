# LogSentry

**A command-line tool that scans Linux `sshd` auth logs and flags security
events** — brute-force attacks, likely account compromises, and reconnaissance
against non-existent usernames.

Built while studying for CompTIA Security+. Pure Python standard library — no
dependencies, runs anywhere.

## Why this exists

Every internet-facing Linux server gets hammered by automated SSH attacks. The
evidence is sitting in `/var/log/auth.log`, but nobody reads thousands of lines
by hand. LogSentry turns that noise into a short, prioritized report: *who is
attacking, how hard, and whether any of them got in.*

## What it detects

- **Brute force** — N+ failed logins from one IP inside a time window.
- **Likely compromise** — a *successful* login from an IP that was brute-forcing
  (the signal that matters most).
- **Recon** — attempts against invalid usernames (`admin`, `oracle`, `pi`…).
- **Top offender IPs** by failed-login count.

## Usage

```bash
python logsentry.py sample_auth.log             # try it on the bundled sample
python logsentry.py /var/log/auth.log --threshold 8 --window 120
python logsentry.py sample_auth.log --json      # machine-readable output
```

Exit code is `1` when brute-force activity is found — so you can wire it into
cron or CI to alert automatically.

## Example output

```
LogSentry report
================================================
lines parsed:        20
failed logins:       16
successful logins:   4
unique source IPs:   4

[!!] LIKELY COMPROMISE - brute force followed by a successful login:
     203.0.113.5  (8 failed, then logged in)

[!] Brute-force sources:
     203.0.113.5      8 fails in window (Jun 10 13:55:31 to Jun 10 13:55:45)  <-- got in!
     192.0.2.77       6 fails in window (Jun 10 14:20:10 to Jun 10 14:20:37)

Top offender IPs (by failed logins):
     203.0.113.5      8
     192.0.2.77       6

Probed non-existent usernames (recon):
     admin            3
     test             1
```

## How it works

- `analyzer.py` — pure parsing + detection logic (self-checking; regex over
  sshd log lines, a two-pointer sweep to count failures within a time window).
- `logsentry.py` — CLI wrapper (argparse) that prints the report or JSON.
- `sample_auth.log` — synthetic log with a real attack pattern to demo against.

## Tests

```bash
pytest -q             # unit + end-to-end on the sample log
python analyzer.py    # zero-dependency self-check
```

CI runs both on every push.

## Note

`sample_auth.log` is synthetic. The IPs are documentation ranges (RFC 5737); no
real hosts or data are involved.
