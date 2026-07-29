"""Parser tests: well-formed lines are understood, malformed lines never crash."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import parser  # noqa: E402


SYSLOG = ("Jul 12 10:31:02 web01 sshd[3311]: Failed password for invalid user "
          "admin from 203.0.113.45 port 40122 ssh2")
APACHE = ('203.0.113.99 - - [12/Jul/2025:09:31:04 +0000] "GET /admin.php HTTP/1.1" '
          '404 162 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"')
JSONL  = '{"timestamp": "2025-07-12T09:31:04Z", "level": "warn", "ip": "203.0.113.7", "message": "denied"}'


class TestSyslog(unittest.TestCase):
    def setUp(self):
        self.entry = parser.parse_lines(SYSLOG)[0]

    def test_source_and_message(self):
        self.assertEqual(self.entry.source, "sshd")
        self.assertIn("Failed password", self.entry.message)

    def test_extracts_ip_and_user(self):
        self.assertEqual(self.entry.ip, "203.0.113.45")
        self.assertEqual(self.entry.user, "admin")

    def test_parses_timestamp_into_datetime(self):
        self.assertIsNotNone(self.entry.dt)
        self.assertEqual((self.entry.dt.month, self.entry.dt.day, self.entry.dt.hour), (7, 12, 10))


class TestApache(unittest.TestCase):
    def setUp(self):
        self.entry = parser.parse_lines(APACHE)[0]

    def test_fields(self):
        self.assertEqual(self.entry.ip, "203.0.113.99")
        self.assertEqual(self.entry.extra["status"], "404")
        self.assertEqual(self.entry.extra["path"], "/admin.php")
        self.assertEqual(self.entry.level, "WARNING")

    def test_user_agent_captured(self):
        self.assertIn("Nmap", self.entry.extra["agent"])

    def test_timestamp_normalised_to_utc(self):
        self.assertIsNotNone(self.entry.dt)
        self.assertIsNone(self.entry.dt.tzinfo)
        self.assertEqual(self.entry.dt.hour, 9)


class TestJsonLines(unittest.TestCase):
    def test_json_fields(self):
        entry = parser.parse_lines(JSONL)[0]
        self.assertEqual(entry.ip, "203.0.113.7")
        self.assertEqual(entry.level, "WARN")
        self.assertEqual(entry.message, "denied")


class TestMalformedInput(unittest.TestCase):
    """The parser must degrade to raw text rather than raise."""

    BAD = "\n".join([
        "not a log line at all",
        "Jul 99 99:99:99 web01 sshd[1]: impossible date",
        '{"broken": "json"',
        "",
        "   ",
        "\x00\x01 binary junk 10.0.0.1",
        "203.0.113.5 - - [nonsense] \"GET / HTTP/1.1\" abc -",
    ])

    def test_does_not_raise(self):
        entries = parser.parse_lines(self.BAD)
        self.assertTrue(all(e.raw for e in entries))

    def test_blank_lines_skipped(self):
        entries = parser.parse_lines(self.BAD)
        self.assertEqual(len(entries), 5)

    def test_impossible_date_leaves_dt_none(self):
        entry = parser.parse_lines("Jul 99 99:99:99 web01 sshd[1]: impossible date")[0]
        self.assertIsNone(entry.dt)

    def test_empty_input(self):
        self.assertEqual(parser.parse_lines(""), [])

    def test_generic_fallback_finds_ip(self):
        entry = parser.parse_lines("something happened at 192.0.2.55 today")[0]
        self.assertEqual(entry.ip, "192.0.2.55")


class TestParseLinesRegression(unittest.TestCase):
    """parse_lines() used to call a nonexistent parse_file.__wrapped__ and crash."""

    def test_parse_lines_returns_entries(self):
        entries = parser.parse_lines(SYSLOG + "\n" + SYSLOG)
        self.assertEqual(len(entries), 2)

    def test_parse_file_and_parse_lines_agree(self):
        here    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sample  = os.path.join(here, "samples", "auth.log")
        with open(sample) as fh:
            text = fh.read()
        self.assertEqual([e.raw for e in parser.parse_file(sample)],
                         [e.raw for e in parser.parse_lines(text)])


if __name__ == "__main__":
    unittest.main()
