
import unittest
import csv
import io

from modules.report_generator import generate_csv_report


class TestReportGenerator(unittest.TestCase):

    def setUp(self):

        self.audit_results = [
            {
                "control": "Windows Firewall",
                "status": "PASS",
                "details": "All firewall profiles are enabled."
            },
            {
                "control": "Microsoft Defender",
                "status": "FAIL",
                "details": "Real-time protection is disabled."
            }
        ]

        self.risk_results = [
            {
                "finding_id": "AUD-001",
                "control": "Windows Firewall",
                "risk_level": "LOW",
                "risk_score": 1,
                "priority": "LOW",
                "risk_explanation": "Firewall is enabled.",
                "recommendation": "Continue monitoring."
            },
            {
                "finding_id": "AUD-002",
                "control": "Microsoft Defender",
                "risk_level": "HIGH",
                "risk_score": 9,
                "priority": "HIGH",
                "risk_explanation": "Protection is disabled.",
                "recommendation": "Investigate Defender settings."
            }
        ]

    def read_report(self, report):

        reader = csv.DictReader(
            io.StringIO(report)
        )

        return list(reader)

    # ======================================
    # BASIC REPORT TESTS
    # ======================================

    def test_csv_report_generation(self):

        report = generate_csv_report(
            self.audit_results,
            self.risk_results
        )

        self.assertIsInstance(report, str)
        self.assertIn("Control", report)
        self.assertIn("Audit Status", report)

    def test_report_contains_all_controls(self):

        report = generate_csv_report(
            self.audit_results,
            self.risk_results
        )

        rows = self.read_report(report)

        self.assertEqual(len(rows), 2)

        controls = [
            row["Control"]
            for row in rows
        ]

        self.assertIn("Windows Firewall", controls)
        self.assertIn("Microsoft Defender", controls)

    def test_report_contains_risk_levels(self):

        report = generate_csv_report(
            self.audit_results,
            self.risk_results
        )

        rows = self.read_report(report)

        self.assertEqual(rows[0]["Risk Level"], "LOW")
        self.assertEqual(rows[1]["Risk Level"], "HIGH")

    def test_report_without_risk_results(self):

        report = generate_csv_report(
            self.audit_results
        )

        rows = self.read_report(report)

        self.assertEqual(
            rows[0]["Risk Level"],
            "NOT ANALYZED"
        )

        self.assertEqual(
            rows[0]["Priority"],
            "NOT ANALYZED"
        )

    # ======================================
    # ENHANCED REPORT TESTS
    # ======================================

    def test_report_contains_finding_ids(self):

        report = generate_csv_report(
            self.audit_results,
            self.risk_results
        )

        rows = self.read_report(report)

        self.assertEqual(rows[0]["Finding ID"], "AUD-001")
        self.assertEqual(rows[1]["Finding ID"], "AUD-002")

    def test_report_contains_risk_scores(self):

        report = generate_csv_report(
            self.audit_results,
            self.risk_results
        )

        rows = self.read_report(report)

        self.assertEqual(rows[0]["Risk Score"], "1")
        self.assertEqual(rows[1]["Risk Score"], "9")

    def test_report_contains_recommendations(self):

        report = generate_csv_report(
            self.audit_results,
            self.risk_results
        )

        rows = self.read_report(report)

        self.assertIn(
            "Continue monitoring.",
            rows[0]["Recommendation"]
        )

        self.assertIn(
            "Investigate Defender settings.",
            rows[1]["Recommendation"]
        )

    def test_report_contains_risk_explanations(self):

        report = generate_csv_report(
            self.audit_results,
            self.risk_results
        )

        rows = self.read_report(report)

        self.assertEqual(
            rows[1]["Risk Explanation"],
            "Protection is disabled."
        )

    def test_report_contains_generated_timestamp(self):

        report = generate_csv_report(
            self.audit_results,
            self.risk_results
        )

        rows = self.read_report(report)

        self.assertTrue(rows[0]["Generated At"])
        self.assertEqual(
            rows[0]["Generated At"],
            rows[1]["Generated At"]
        )

    # ======================================
    # INPUT VALIDATION TESTS
    # ======================================

    def test_reject_invalid_audit_results(self):

        with self.assertRaises(TypeError):
            generate_csv_report("invalid data")

    def test_reject_invalid_audit_record(self):

        with self.assertRaises(ValueError):
            generate_csv_report([
                "invalid record"
            ])

    def test_reject_invalid_risk_results(self):

        with self.assertRaises(TypeError):
            generate_csv_report(
                self.audit_results,
                "invalid risk data"
            )

    def test_reject_invalid_risk_record(self):

        with self.assertRaises(ValueError):
            generate_csv_report(
                self.audit_results,
                ["invalid record"]
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
