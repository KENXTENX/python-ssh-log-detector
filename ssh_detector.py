"""Read-only, dependency-free SSH failure detector for supplied log files."""

import argparse
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import re
import sys

ISO = re.compile(r"^(?P<stamp>\d{4}-\d{2}-\d{2}T\S+)\s+\S+\s+sshd(?:\[\d+\])?:\s+(?P<body>.*)$")
LEGACY = re.compile(r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd(?:\[\d+\])?:\s+(?P<body>.*)$")
FAILED = re.compile(r"^Failed (?P<method>password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?:\s|$)")


@dataclass(frozen=True)
class Event:
    time: datetime
    ip: str
    method: str
    raw: str


def parse_failure(raw: str, *, legacy_year: int | None = None) -> Event | None:
    """Parse a recognized OpenSSH failure, skipping unrelated messages.

    Raises ValueError for invalid timestamp/IP/port of recognized failures.
    """
    line = raw.rstrip("\r\n")
    m = ISO.match(line)
    form = "iso"
    if m is None:
        m = LEGACY.match(line)
        form = "legacy"
    if m is None:
        return None
    failure = FAILED.match(m.group("body"))
    if failure is None:
        return None

    if form == "iso":
        try:
            time = datetime.fromisoformat(m.group("stamp").replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid ISO timestamp") from exc
        if time.tzinfo is None or time.utcoffset() is None:
            raise ValueError("timestamp lacks timezone")
        time = time.astimezone(timezone.utc)
    else:
        if legacy_year is None:
            raise ValueError("legacy date needs --legacy-year")
        if not 2000 <= legacy_year <= 2100:
            raise ValueError("legacy year out of range")
        try:
            time = datetime.strptime(
                f"{legacy_year} {m.group('month')} {m.group('day')} {m.group('clock')}",
                "%Y %b %d %H:%M:%S",
            ).replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise ValueError("invalid legacy timestamp") from exc

    try:
        ip = str(ipaddress.ip_address(failure.group("ip")))
    except ValueError as exc:
        raise ValueError("invalid source IP") from exc
    port = int(failure.group("port"))
    if not 1 <= port <= 65535:
        raise ValueError("invalid source port")
    return Event(time, ip, failure.group("method"), line)


def detect(events: list[Event], *, threshold: int = 5, window: int = 60) -> list[dict]:
    """One alert per continuously qualifying source-IP burst."""
    if threshold < 2 or window < 1:
        raise ValueError("threshold >= 2 and window >= 1 required")
    distinct = {e.raw: e for e in events}
    recent: dict[str, deque[Event]] = defaultdict(deque)
    active: dict[str, bool] = defaultdict(bool)
    alerts: list[dict] = []
    for e in sorted(distinct.values(), key=lambda item: (item.time, item.ip)):
        bucket = recent[e.ip]
        cutoff = e.time - timedelta(seconds=window)
        while bucket and bucket[0].time < cutoff:
            bucket.popleft()
        bucket.append(e)
        if len(bucket) < threshold:
            active[e.ip] = False
        elif not active[e.ip]:
            def fmt(t: datetime) -> str:
                return t.isoformat(timespec="seconds").replace("+00:00", "Z")
            alerts.append({
                "rule_id": "SSH-001",
                "source_ip": e.ip,
                "failure_count": len(bucket),
                "window_seconds": window,
                "first_seen_utc": fmt(bucket[0].time),
                "last_seen_utc": fmt(e.time),
            })
            active[e.ip] = True
    return alerts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Defensive analysis of supplied OpenSSH logs")
    parser.add_argument("logfile", help="Text log filename or - for stdin")
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window", type=int, default=60, help="Seconds (inclusive)")
    parser.add_argument("--legacy-year", type=int, help="Explicit year; legacy timestamps treated as UTC")
    parser.add_argument("--strict", action="store_true", help="Reject malformed recognized failures")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--fail-on-alert", action="store_true", help="Return exit code 1 on detection")
    args = parser.parse_args(argv)
    if args.threshold < 2 or args.window < 1:
        print("error: threshold >= 2 and window >= 1 required", file=sys.stderr)
        return 2
    if args.legacy_year is not None and not 2000 <= args.legacy_year <= 2100:
        print("error: invalid legacy year", file=sys.stderr)
        return 2

    records: list[Event] = []
    total = ignored = invalid = duplicates = 0
    seen: set[str] = set()
    try:
        stream = sys.stdin if args.logfile == "-" else Path(args.logfile).open(
            "r", encoding="utf-8", errors="replace"
        )
        try:
            for line in stream:
                total += 1
                try:
                    e = parse_failure(line, legacy_year=args.legacy_year)
                except ValueError as exc:
                    invalid += 1
                    if args.strict:
                        print(f"error on line {total}: {exc}", file=sys.stderr)
                        return 2
                    continue
                if e is None:
                    ignored += 1
                elif e.raw in seen:
                    duplicates += 1
                else:
                    records.append(e)
                    seen.add(e.raw)
        finally:
            if stream is not sys.stdin:
                stream.close()
    except OSError as exc:
        print(f"error reading log: {exc}", file=sys.stderr)
        return 2

    alerts = detect(records, threshold=args.threshold, window=args.window)
    summary = {
        "total_lines": total, "matched_failures": len(records),
        "ignored_lines": ignored, "invalid_lines": invalid,
        "duplicate_lines": duplicates, "alerts": len(alerts),
    }
    if args.json:
        print(json.dumps({"rule_id": "SSH-001", "summary": summary, "alerts": alerts}, indent=2))
    else:
        print(f"SSH-001: {len(records)} failures, {len(alerts)} alerts, {invalid} invalid")
        for a in alerts:
            print(f"ALERT {a['source_ip']}: {a['failure_count']} failed logins within {window if False else args.window}s")
    return 1 if args.fail_on_alert and alerts else 0


if __name__ == "__main__":
    raise SystemExit(main())
