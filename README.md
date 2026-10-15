# LogSentry

**A command-line tool that scans Linux `sshd` auth logs and flags security
events** — brute-force attacks, likely account compromises, and reconnaissance
against non-existent usernames.

Pure Python standard library — no dependencies, runs anywhere.

## Why this exists

Every internet-facing Linux server gets hammered by automated SSH attacks. The
evidence is sitting in `/var/log/auth.log`, but nobody reads thousands of lines
by hand. LogSentry turns that noise into a short, prioritized report: *who is
attacking, how hard, and whether any of them got in.*

## What it detects

- **Brute force** — N+ failed logins from one IP inside a time window.
- **Likely compromise** — a *successful* login from a brute-forcing IP that
  happens at or after the start of its burst (the signal that matters most). A
  login from the same IP *before* the attack is not flagged.
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

Real output of `python logsentry.py sample_auth.log`:

```
LogSentry report
================================================
lines parsed:        22
failed logins:       16
successful logins:   6
unique source IPs:   4

[!!] LIKELY COMPROMISE - brute force followed by a successful login:
     203.0.113.5  (8 failed, then logged in at Jun 10 13:55:52)

[!] Brute-force sources:
     203.0.113.5      8 fails in window (Jun 10 13:55:31 to Jun 10 13:55:45)  <-- got in!
     192.0.2.77       6 fails in window (Jun 10 14:20:10 to Jun 10 14:20:37)

Top offender IPs (by failed logins):
     203.0.113.5      8
     192.0.2.77       6
     198.51.100.2     1
     198.51.100.9     1

Probed non-existent usernames (recon):
     admin            3
     test             1
     oracle           1
     ubuntu           1
     pi               1
```

## Supported log formats

- Classic syslog timestamps (`Jun 10 13:55:31`). These carry no year, so
  LogSentry assumes the most recent past occurrence of that date (December
  lines read in January go to last year; `Feb 29` goes to the latest leap year).
  Pass `--year` to force one.
- ISO-8601 / RFC 3339 timestamps (`2025-06-10T13:55:31.123456-03:00`, as
  written by rsyslog high-precision templates or `journalctl -o short-iso`).
  Timestamps with an offset are converted to UTC. Mixing both formats in one
  file is not supported, since syslog times are local and ISO ones UTC.
- Any sshd auth method: `password`, `publickey`, `keyboard-interactive/pam`…
- IPv4 and IPv6 source addresses (IPv6 normalized, so `2001:db8:0::5` and
  `2001:db8::5` count as the same host).

The file is read as a stream, line by line; only per-IP timestamps are kept in
memory.

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

## What I Learned

_TODO: section to be written by the author._

## Note

`sample_auth.log` is synthetic. The IPs are documentation ranges (RFC 5737); no
real hosts or data are involved.
