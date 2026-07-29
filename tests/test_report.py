"""Scoring, severity filtering, JSON shape and end-to-end CLI tests."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import log_analyzer  # noqa: E402
import models        # noqa: E402
import reporter      # noqa: E402

DEMO_LOGS = log_analyzer.DEMO_LOGS


def _alert(severity, count=1, rule_id="LS999"):
    return models.Alert(rule_id=rule_id, rule_name="test rule", severity=severity,
                        description="d", why="w", count=count)


class TestSeverityFilter(unittest.TestCase):
    def setUp(self):
        self.alerts = [_alert("LOW"), _alert("MEDIUM"), _alert("HIGH"), _alert("CRITICAL")]

    def test_no_filter_keeps_everything(self):
        self.assertEqual(len(models.filter_by_severity(self.alerts, None)), 4)

    def test_high_and_above(self):
        kept = models.filter_by_severity(self.alerts, "HIGH")
        self.assertEqual([a.severity for a in kept], ["HIGH", "CRITICAL"])

    def test_critical_only(self):
        self.assertEqual(len(models.filter_by_severity(self.alerts, "CRITICAL")), 1)

    def test_filter_is_case_insensitive(self):
        self.assertEqual(len(models.filter_by_severity(self.alerts, "high")), 2)


class TestRiskScore(unittest.TestCase):
    def test_no_findings_scores_zero(self):
        self.assertEqual(models.risk_score([]), {"score": 0, "level": "NONE",
                                                 "formula": models.RISK_FORMULA})

    def test_known_values(self):
        # HIGH(10) x1.0 + MEDIUM(5) x1.5 (7 events) = 17.5 -> 18
        score = models.risk_score([_alert("HIGH", 2), _alert("MEDIUM", 7)])
        self.assertEqual(score["score"], 18)
        self.assertEqual(score["level"], "LOW")

    def test_volume_multiplier_steps(self):
        self.assertEqual(models.volume_multiplier(1), 1.0)
        self.assertEqual(models.volume_multiplier(5), 1.5)
        self.assertEqual(models.volume_multiplier(20), 2.0)

    def test_score_is_capped_at_100(self):
        self.assertEqual(models.risk_score([_alert("CRITICAL", 50)] * 10)["score"], 100)

    def test_levels(self):
        self.assertEqual(models.risk_level(0), "NONE")
        self.assertEqual(models.risk_level(24), "LOW")
        self.assertEqual(models.risk_level(25), "MEDIUM")
        self.assertEqual(models.risk_level(50), "HIGH")
        self.assertEqual(models.risk_level(75), "CRITICAL")

    def test_deterministic_across_runs(self):
        entries, alerts = log_analyzer.analyse(DEMO_LOGS)
        first  = models.risk_score(alerts)
        _, alerts2 = log_analyzer.analyse(DEMO_LOGS)
        self.assertEqual(first, models.risk_score(alerts2))
        self.assertEqual(first["score"], models.risk_score(alerts)["score"])


class TestJsonReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        entries, alerts = log_analyzer.analyse(DEMO_LOGS)
        cls.report = reporter.build_report(alerts, len(entries), 0.01,
                                           risk=models.risk_score(alerts),
                                           files=DEMO_LOGS, severity_filter=None)

    def test_top_level_keys(self):
        self.assertEqual(set(self.report), {
            "tool", "schema_version", "generated", "files_analysed", "total_log_entries",
            "elapsed_sec", "severity_filter", "risk", "finding_count", "findings",
            "top_source_ips"})

    def test_finding_keys(self):
        for finding in self.report["findings"]:
            self.assertEqual(set(finding), {
                "rule_id", "rule_name", "severity", "description", "why", "mitre",
                "matched_count", "samples"})

    def test_risk_keys(self):
        self.assertEqual(set(self.report["risk"]), {"score", "level", "formula"})

    def test_findings_sorted_by_rule_id(self):
        ids = [f["rule_id"] for f in self.report["findings"]]
        self.assertEqual(ids, sorted(ids))

    def test_report_is_json_serialisable(self):
        self.assertIsInstance(json.dumps(self.report), str)

    def test_empty_report_has_same_shape(self):
        empty = reporter.build_report([], 0, 0.0)
        self.assertEqual(set(empty), set(self.report))
        self.assertEqual(empty["findings"], [])


class TestCli(unittest.TestCase):
    """Runs the real CLI in a subprocess: no network, only bundled sample logs."""

    def _run(self, *args):
        return subprocess.run([sys.executable, "log_analyzer.py", *args],
                              cwd=ROOT, capture_output=True, text=True)

    def test_demo_runs(self):
        proc = self._run("--demo")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("LogSentry", proc.stdout)
        self.assertIn("Risk", proc.stdout)

    def test_file_flag(self):
        proc = self._run("--file", os.path.join("samples", "auth.log"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("LS001", proc.stdout)

    def test_severity_flag_filters_output(self):
        everything = self._run("--demo").stdout
        critical   = self._run("--demo", "--severity", "CRITICAL").stdout
        self.assertIn("[MEDIUM]", everything)
        self.assertNotIn("[MEDIUM]", critical)
        self.assertIn("[CRITICAL]", critical)

    def test_json_export_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "report.json")
            proc = self._run("--demo", "--json", out)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(out) as fh:
                data = json.load(fh)
        self.assertEqual(data["tool"], "LogSentry")
        self.assertGreaterEqual(data["finding_count"], 10)
        self.assertEqual(data["finding_count"], len(data["findings"]))

    def test_output_is_an_alias_for_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "report.json")
            self._run("--demo", "--output", out)
            with open(out) as fh:
                self.assertIn("findings", json.load(fh))

    def test_no_arguments_exits_nonzero(self):
        self.assertEqual(self._run().returncode, 1)

    def test_missing_file_exits_nonzero(self):
        proc = self._run("--file", "does-not-exist.log")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("not found", proc.stderr)

    def test_list_rules(self):
        proc = self._run("--list-rules")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("LS001", proc.stdout)


if __name__ == "__main__":
    unittest.main()
