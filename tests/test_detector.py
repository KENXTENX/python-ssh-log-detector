"""Only invented SSH log lines and synthetic events are used."""
import io
import json
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from ssh_detector import Event, detect, main, parse_failure


EXAMPLE = "2026-10-22T12:00:00Z test sshd[1]: Failed password for invalid user demo from 192.0.2.1 port 50001 ssh2"
START = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)


def e(sec, ip="192.0.2.1", label=None):
    return Event(START + timedelta(seconds=sec), ip, "password", f"event-{ip}-{sec if label is None else label}")


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        status = main(list(args))
    return status, out.getvalue(), err.getvalue()


class ParseTests(unittest.TestCase):
    def test_password(self):
        self.assertEqual(parse_failure(EXAMPLE).ip, "192.0.2.1")
    def test_username_does_not_affect_ip(self):
        self.assertEqual(parse_failure(EXAMPLE.replace("invalid user ", "")).ip, "192.0.2.1")
    def test_publickey(self):
        self.assertEqual(parse_failure(EXAMPLE.replace("Failed password", "Failed publickey")).method, "publickey")
    def test_ipv6(self):
        self.assertEqual(parse_failure(EXAMPLE.replace("192.0.2.1", "2001:db8::1")).ip, "2001:db8::1")
    def test_offset(self):
        self.assertEqual(parse_failure(EXAMPLE.replace("12:00:00Z", "08:00:00-04:00")).time, START)
    def test_success_ignored(self):
        self.assertIsNone(parse_failure(EXAMPLE.replace("Failed password", "Accepted password")))
    def test_other_line_ignored(self):
        self.assertIsNone(parse_failure("system starting"))
    def test_invalid_ip(self):
        with self.assertRaises(ValueError):
            parse_failure(EXAMPLE.replace("192.0.2.1", "bad-ip"))
    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            parse_failure(EXAMPLE.replace("50001", "70000"))
    def test_naive_time(self):
        with self.assertRaises(ValueError):
            parse_failure(EXAMPLE.replace("12:00:00Z", "12:00:00"))
    def test_invalid_date(self):
        with self.assertRaises(ValueError):
            parse_failure(EXAMPLE.replace("2026-10-22", "2026-02-30"))
    def test_legacy_requires_year(self):
        log = "Oct 22 12:00:00 host sshd[1]: Failed password for demo from 192.0.2.1 port 50001 ssh2"
        with self.assertRaises(ValueError):
            parse_failure(log)
    def test_legacy_explicit_year(self):
        log = "Oct 22 12:00:00 host sshd[1]: Failed password for demo from 192.0.2.1 port 50001 ssh2"
        self.assertEqual(parse_failure(log, legacy_year=2026).time.year, 2026)


class DetectionTests(unittest.TestCase):
    def test_threshold(self):
        self.assertEqual(len(detect([e(x) for x in range(5)])), 1)
    def test_below_threshold(self):
        self.assertEqual(len(detect([e(x) for x in range(4)])), 0)
    def test_per_ip(self):
        self.assertEqual(len(detect([e(i, "192.0.2.1") for i in range(3)] + [e(i, "192.0.2.2") for i in range(3)])), 0)
    def test_two_sources(self):
        self.assertEqual(len(detect([e(i, "192.0.2.1") for i in range(5)] + [e(i, "192.0.2.2") for i in range(5)])), 2)
    def test_inclusive_boundary(self):
        self.assertEqual(len(detect([e(i) for i in [0, 15, 30, 45, 60]])), 1)
    def test_expired_first_event(self):
        self.assertEqual(len(detect([e(i) for i in [0, 16, 32, 48, 65]])), 0)
    def test_out_of_order(self):
        self.assertEqual(len(detect([e(i) for i in [4, 2, 0, 3, 1]])), 1)
    def test_repeated_identical_line(self):
        self.assertEqual(len(detect([e(i, label="same") for i in range(5)])), 0)
    def test_simultaneous_distinct_events(self):
        self.assertEqual(len(detect([e(0, label=i) for i in range(5)])), 1)
    def test_second_burst_after_idle(self):
        self.assertEqual(len(detect([e(i) for i in range(5)] + [e(i + 100) for i in range(5)])), 2)
    def test_sustained_burst_one_alert(self):
        self.assertEqual(len(detect([e(i * 3) for i in range(30)])), 1)
    def test_rule_fields(self):
        a = detect([e(i) for i in range(5)])[0]
        self.assertEqual((a["rule_id"], a["failure_count"]), ("SSH-001", 5))
    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            detect([], threshold=1)
    def test_invalid_window(self):
        with self.assertRaises(ValueError):
            detect([], window=0)


class CLITests(unittest.TestCase):
    def setUp(self):
        self.fixture = str(Path(__file__).resolve().parents[1] / "fixtures" / "synthetic_auth.log")
    def test_json_fixture(self):
        code, output, _ = run(self.fixture, "--json")
        obj = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual((obj["summary"]["matched_failures"], len(obj["alerts"])), (7, 1))
    def test_alert_exit(self):
        code, _, _ = run(self.fixture, "--fail-on-alert")
        self.assertEqual(code, 1)
    def test_missing_file(self):
        code, _, err = run("/file/that/does/not/exist")
        self.assertEqual(code, 2)
        self.assertIn("error", err)
    def test_bad_threshold(self):
        self.assertEqual(run(self.fixture, "--threshold", "1")[0], 2)
    def test_empty_log(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "empty.log"
            p.write_text("", encoding="utf8")
            code, stdout, _ = run(str(p), "--json")
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stdout)["alerts"], [])
    def test_duplicate_reporting(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "dups.log"
            p.write_text((EXAMPLE + "\n") * 6, encoding="utf8")
            code, stdout, _ = run(str(p), "--json")
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stdout)["summary"]["duplicate_lines"], 5)
    def test_strict_rejects_malformed(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.log"
            p.write_text(EXAMPLE.replace("192.0.2.1", "not-ip"), encoding="utf8")
            self.assertEqual(run(str(p), "--strict")[0], 2)
