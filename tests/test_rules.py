"""Rule tests: every rule fires on a crafted positive and stays quiet on a benign negative."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import parser  # noqa: E402
import rules   # noqa: E402


# Benign traffic every rule must ignore: ordinary logins, a normal sudo command,
# cron root sessions, a couple of 404s and small responses.
BENIGN = """\
Jul 12 08:15:03 web01 sshd[2610]: Accepted publickey for jsmith from 198.51.100.23 port 49770 ssh2
Jul 12 08:15:03 web01 sshd[2610]: pam_unix(sshd:session): session opened for user jsmith by (uid=0)
Jul 12 09:12:05 web01 sudo:   jsmith : TTY=pts/0 ; PWD=/home/jsmith ; USER=root ; COMMAND=/usr/bin/apt update
Jul 12 13:30:02 web01 CRON[3811]: pam_unix(cron:session): session opened for user root by (uid=0)
Jul 12 07:40:12 web01 systemd[1]: Started Security Auditing Service.
Jul 12 10:31:35 web01 sshd[3323]: Failed password for admin from 203.0.113.45 port 40202 ssh2
"""

BENIGN_WEB = """\
198.51.100.10 - - [12/Jul/2025:08:02:11 +0000] "GET / HTTP/1.1" 200 5120 "-" "Chrome/126.0"
198.51.100.10 - - [12/Jul/2025:08:02:12 +0000] "GET /static/app.css HTTP/1.1" 200 8442 "-" "Chrome/126.0"
198.51.100.61 - - [12/Jul/2025:08:31:02 +0000] "GET /favicon.ico HTTP/1.1" 404 162 "-" "Firefox/127.0"
198.51.100.44 - - [12/Jul/2025:13:02:18 +0000] "POST /checkout HTTP/1.1" 200 2210 "-" "Safari/605.1"
"""


def _fails(n, ip="203.0.113.45"):
    return "".join(
        f"Jul 12 10:31:{i:02d} web01 sshd[33{i:02d}]: Failed password for invalid user "
        f"admin from {ip} port 401{i:02d} ssh2\n" for i in range(n))


def _scan_404(n, ip="203.0.113.99"):
    return "".join(
        f'{ip} - - [12/Jul/2025:09:31:{i:02d} +0000] "GET /probe{i}.php HTTP/1.1" 404 162 "-" "scan"\n'
        for i in range(n))


# rule function -> (positive log text, expected minimum matched events)
POSITIVES = {
    "rule_ssh_brute_force": _fails(6),
    "rule_success_after_failures":
        _fails(4) + "Jul 12 10:33:47 web01 sshd[3341]: Accepted password for admin "
                    "from 203.0.113.45 port 41988 ssh2\n",
    "rule_root_session":
        "Jul 12 02:14:09 web01 sshd[2051]: Accepted password for root from 198.51.100.23 port 41022 ssh2\n",
    "rule_audit_tampering":
        "Jul 12 02:15:22 web01 auditd[812]: The audit daemon is exiting.\n",
    "rule_new_account":
        "Jul 12 02:16:44 web01 useradd[2210]: new user: name=svc_backup, UID=1004, GID=1004, "
        "home=/home/svc_backup, shell=/bin/bash\n",
    "rule_sudo_misuse":
        "Jul 12 09:21:40 web01 sudo:   webdev : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/webdev ; "
        "USER=root ; COMMAND=/usr/bin/id\n",
    "rule_off_hours_login":
        "Jul 12 02:14:09 web01 sshd[2051]: Accepted password for root from 198.51.100.23 port 41022 ssh2\n",
    "rule_rapid_ip_change":
        "Jul 12 09:02:41 web01 sshd[2688]: Accepted publickey for jsmith from 198.51.100.23 port 49820 ssh2\n"
        "Jul 12 09:07:58 web01 sshd[2701]: Accepted password for jsmith from 203.0.113.77 port 33110 ssh2\n",
    "rule_path_traversal":
        '203.0.113.88 - - [12/Jul/2025:10:02:14 +0000] "GET /download.php?file=../../../etc/passwd '
        'HTTP/1.1" 200 1834 "-" "curl/8.4.0"\n',
    "rule_sql_injection":
        '203.0.113.88 - - [12/Jul/2025:10:05:31 +0000] "GET /search.php?q=1%20UNION%20SELECT%20pw%20'
        'FROM%20users HTTP/1.1" 200 9330 "-" "curl/8.4.0"\n',
    "rule_scanner_404_burst": _scan_404(16),
    "rule_large_transfer":
        '203.0.113.45 - - [12/Jul/2025:10:44:52 +0000] "GET /exports/all.csv HTTP/1.1" 200 268435456 '
        '"-" "curl/8.4.0"\n',
}


class TestRuleRegistry(unittest.TestCase):
    def test_at_least_ten_rules(self):
        self.assertGreaterEqual(len(rules.ALL_RULES), 10)

    def test_ids_and_names_unique(self):
        catalogue = rules.rule_catalogue()
        self.assertEqual(len(catalogue), len({r.id for r in catalogue}))
        self.assertEqual(len(catalogue), len({r.name for r in catalogue}))

    def test_every_rule_has_metadata(self):
        for rule in rules.rule_catalogue():
            with self.subTest(rule=rule.id):
                self.assertTrue(rule.id and rule.name and rule.why)
                self.assertIn(rule.severity, ("LOW", "MEDIUM", "HIGH", "CRITICAL"))

    def test_every_rule_has_a_positive_fixture(self):
        names = {fn.__name__ for fn in rules.ALL_RULES}
        self.assertEqual(names, set(POSITIVES), "add a positive case for every rule")


class TestRulesFireOnPositives(unittest.TestCase):
    def test_positive_cases(self):
        for fn in rules.ALL_RULES:
            with self.subTest(rule=fn.rule.id):
                alert = fn(parser.parse_lines(POSITIVES[fn.__name__]))
                self.assertIsNotNone(alert, f"{fn.rule.id} did not fire on its positive case")
                self.assertEqual(alert.rule_id, fn.rule.id)
                self.assertGreaterEqual(alert.count, 1)


class TestRulesQuietOnNegatives(unittest.TestCase):
    def test_benign_auth_log(self):
        entries = parser.parse_lines(BENIGN)
        for fn in rules.ALL_RULES:
            with self.subTest(rule=fn.rule.id):
                self.assertIsNone(fn(entries), f"{fn.rule.id} fired on benign auth traffic")

    def test_benign_web_log(self):
        entries = parser.parse_lines(BENIGN_WEB)
        for fn in rules.ALL_RULES:
            with self.subTest(rule=fn.rule.id):
                self.assertIsNone(fn(entries), f"{fn.rule.id} fired on benign web traffic")

    def test_empty_input(self):
        for fn in rules.ALL_RULES:
            with self.subTest(rule=fn.rule.id):
                self.assertIsNone(fn([]))


class TestRuleEdges(unittest.TestCase):
    def test_brute_force_respects_threshold(self):
        self.assertIsNone(rules.rule_ssh_brute_force(parser.parse_lines(_fails(4))))

    def test_success_without_enough_failures_is_quiet(self):
        text = ("Jul 12 02:14:01 web01 sshd[2044]: Failed password for root from 198.51.100.23 port 41010 ssh2\n"
                "Jul 12 02:14:09 web01 sshd[2051]: Accepted password for root from 198.51.100.23 port 41022 ssh2\n")
        self.assertIsNone(rules.rule_success_after_failures(parser.parse_lines(text)))

    def test_cron_root_session_is_not_an_interactive_root_login(self):
        text = "Jul 12 13:30:02 web01 CRON[3811]: pam_unix(cron:session): session opened for user root by (uid=0)\n"
        self.assertIsNone(rules.rule_root_session(parser.parse_lines(text)))

    def test_shell_command_does_not_trigger_web_rules(self):
        text = ("Jul 12 09:20:11 web01 sudo:   webdev : 3 incorrect password attempts ; TTY=pts/2 ; "
                "PWD=/home/webdev ; USER=root ; COMMAND=/bin/cat /etc/shadow\n")
        self.assertIsNone(rules.rule_path_traversal(parser.parse_lines(text)))

    def test_daytime_login_is_not_off_hours(self):
        text = "Jul 12 14:18:27 web01 sshd[3902]: Accepted publickey for jsmith from 198.51.100.23 port 50112 ssh2\n"
        self.assertIsNone(rules.rule_off_hours_login(parser.parse_lines(text)))

    def test_same_ip_relogin_is_not_a_rapid_ip_change(self):
        text = ("Jul 12 09:02:41 web01 sshd[2688]: Accepted publickey for jsmith from 198.51.100.23 port 49820 ssh2\n"
                "Jul 12 09:07:58 web01 sshd[2701]: Accepted password for jsmith from 198.51.100.23 port 33110 ssh2\n")
        self.assertIsNone(rules.rule_rapid_ip_change(parser.parse_lines(text)))

    def test_small_response_is_not_a_large_transfer(self):
        text = ('203.0.113.45 - - [12/Jul/2025:10:44:52 +0000] "GET /a.csv HTTP/1.1" 200 1024 "-" "curl/8.4.0"\n')
        self.assertIsNone(rules.rule_large_transfer(parser.parse_lines(text)))

    def test_scanner_burst_respects_threshold(self):
        self.assertIsNone(rules.rule_scanner_404_burst(parser.parse_lines(_scan_404(5))))


if __name__ == "__main__":
    unittest.main()
