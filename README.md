# Python SSH Log Detector

**Cereus Learning — Portfolio Project 02**

A defensive, dependency-free Python tool that examines OpenSSH authentication failures, groups them by source IP, and detects bursts within a configurable sliding time window.

**Status:** Development branch. No live monitoring or simulated attacks have been performed. All included logs are synthetic.

## Why this exists

Administrators need a repeatable way to triage suspicious repeated login failures. The detector emits readable and structured JSON alerts for later SIEM integration, without initiating logins, probing systems, modifying firewalls or blocking IPs.

## Quick start

Requires **Python 3.10+**. Run from this repository:

```bash
python3 -m unittest discover -s tests -v
python3 ssh_detector.py fixtures/synthetic_auth.log --json
python3 ssh_detector.py fixtures/synthetic_auth.log --json --fail-on-alert
echo "Exit code: $?"
```

Exit codes: `0` processed successfully; `1` alert(s) found if `--fail-on-alert` was selected; `2` invalid input or strict parsing error.

## Rule SSH-001

- Default: 5 failures from one source address within an **inclusive 60-second window**.
- Parses `Failed password` and `Failed publickey` OpenSSH messages.
- Supports IPv4, IPv6, timezone-aware ISO timestamps, and legacy syslog dates with an explicitly supplied year.
- Ignores unrelated/`Invalid user` notices (so one failed login is not counted twice).
- Sorts events chronologically and deduplicates identical input log lines.
- Emits one alert for a continuous burst; re-arms when the window falls below threshold.

Examples:

```bash
python3 ssh_detector.py fixtures/synthetic_auth.log --threshold 5 --window 60
python3 ssh_detector.py fixtures/synthetic_auth.log --json
python3 ssh_detector.py /path/to/sanitized-auth.log --legacy-year 2026 --json
```

Traditional syslog logs have no year or timezone. This lab assumes UTC for `--legacy-year` input; normalize local-time logs before relying on their time windows.

## Files

- `ssh_detector.py` — parser, rule, CLI and JSON reports
- `tests/` — deterministic synthetic-data unit tests
- `fixtures/synthetic_auth.log` — invented events using documentation-reserved addresses
- `.github/workflows/tests.yml` — CI tests and smoke check
- `docs/` — architecture, limitations and evidence checklist

## Security and limitations

A threshold alert is **not proof of account compromise**. Shared NAT users and misconfigured automation can create false positives; distributed or slow attempts may not be detected. This is a batch analysis project, not a real-time SOC agent, and it does not parse every possible Linux log variant. Do not publish real authentication logs, usernames, hostnames, passwords, SSH keys, or real source addresses.

See [Architecture](docs/architecture.md) and [Evidence](docs/evidence.md).

**Created by KENNxTENNx · Cereus Learning · © 2026**